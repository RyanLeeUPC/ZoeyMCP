"""The approval ledger's record format, hash chain and recovery rules (M4 design F).

One canonical JSON record per line, at most :data:`MAX_LINE_BYTES` with its newline. Every record
carries ``v``, a gapless ``seq``, ``prev`` (the ``sha256:`` of the previous line, without its
newline), ``ts`` (UTC milliseconds), ``ref``, ``kind`` and ``writer``. Arguments and prompt text
appear only as keyed digests (``hmac-sha256:``), never as values.

This module is pure and standard library only, so the gateway writes these records and M8's vault
can write the same ones. :mod:`zoeymcp.gateway.ledger` does the file I/O around it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from . import canonical

VERSION: Final = 1
MAX_LINE_BYTES: Final = 4096
GENESIS: Final = "sha256:" + "0" * 64

Kind = Literal["asked", "decided", "outcome", "recovered", "repaired"]
# B.4's decisions; approved_elsewhere and pending are reserved for M8, so a v1 reader accepts them.
DECISIONS: Final = frozenset(
    {
        "accept",
        "decline",
        "dismiss",
        "code_mismatch",
        "timeout",
        "withdrawn",
        "stream_lost",
        "unavailable",
        "error",
        "mismatch",
        "changed",
        "shutdown",
        "abandoned",
        "approved_elsewhere",
        "pending",
    }
)
OUTCOMES: Final = frozenset(
    {"ok", "tool_error", "upstream_error", "refused", "not_sent", "unknown"}
)
DETAILS: Final = frozenset(
    {
        "sent",
        "smtp_refused",
        "changed",
        "upstream_input_required",
        "restart",
        "session_expired",
        "shutdown",
    }
)

_REF = re.compile(r"^[0-9a-f]{16}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HMAC = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_COMMON = ("v", "seq", "prev", "ts", "ref", "kind", "writer")


class LedgerFormatError(ValueError):
    """A line that isn't a valid v1 ledger record. The message never holds field values."""


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _name(value: Any) -> bool:
    return isinstance(value, str) and bool(_NAME.match(value))


def _member(options: frozenset[str]) -> Any:
    return lambda value: isinstance(value, str) and value in options


def _optional(check: Any) -> Any:
    return lambda value: value is None or check(value)


def _pattern(regex: re.Pattern[str]) -> Any:
    return lambda value: isinstance(value, str) and bool(regex.match(value))


# The fields each kind carries, besides the common ones, and their checks.
FIELDS: Final[Mapping[str, Mapping[str, Any]]] = {
    "asked": {
        "client": _name,
        "server": _name,
        "tool": _name,
        "where": _member(frozenset({"gateway", "vault"})),
        "era": _member(frozenset({"legacy", "modern"})),
        "args": _pattern(_HMAC),
        "pin": _pattern(_SHA256),
        "text": _pattern(_HMAC),
        "chars": _count,
        "writes": _count,
        "expires": _count,
    },
    "decided": {"decision": _member(DECISIONS), "waited_ms": _count},
    "outcome": {
        "outcome": _member(OUTCOMES),
        "detail": _optional(_member(DETAILS)),
        "writes_sent": _count,
        "writes_unknown": _count,
    },
    "recovered": {"abandoned": _count, "not_sent": _count, "unknown": _count},
    "repaired": {"torn_bytes": _count},
}
# Kinds about the ledger itself rather than one call carry no ref.
_NO_REF: Final = frozenset({"recovered", "repaired"})


@dataclass(frozen=True)
class Record:
    """One parsed ledger line."""

    seq: int
    prev: str
    ts: int
    ref: str | None
    kind: Kind
    writer: str
    fields: Mapping[str, Any]
    line: bytes  # without its newline
    hash: str  # sha256: of ``line``


def line_hash(line: bytes) -> str:
    """The ``sha256:`` of one line without its newline: the next record's ``prev``."""
    return "sha256:" + hashlib.sha256(line.rstrip(b"\n")).hexdigest()


def encode(
    kind: Kind,
    *,
    seq: int,
    prev: str,
    ts: int,
    ref: str | None,
    writer: str = "gateway",
    **fields: Any,
) -> bytes:
    """One record as its line, newline included. Raises :class:`LedgerFormatError`."""
    value = {
        "v": VERSION,
        "seq": seq,
        "prev": prev,
        "ts": ts,
        "ref": ref,
        "kind": kind,
        "writer": writer,
        **fields,
    }
    _check(value)
    line = canonical.dumps_canonical(value) + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise LedgerFormatError(f"a {kind} record is longer than {MAX_LINE_BYTES} bytes")
    return line


def parse(line: bytes) -> Record:
    """Parse one line (with or without its newline). Raises :class:`LedgerFormatError`."""
    body = line[:-1] if line.endswith(b"\n") else line
    if len(body) + 1 > MAX_LINE_BYTES:
        raise LedgerFormatError(f"a record is longer than {MAX_LINE_BYTES} bytes")
    try:
        value = canonical.loads_strict(body, max_bytes=MAX_LINE_BYTES)
    except (canonical.JSONRejected, ValueError) as exc:
        raise LedgerFormatError("not a JSON record") from exc
    if not isinstance(value, dict):
        raise LedgerFormatError("not a JSON object")
    _check(value)
    if canonical.dumps_canonical(value) != body:
        raise LedgerFormatError("not in canonical form")
    extra = {k: v for k, v in value.items() if k not in _COMMON}
    return Record(
        seq=value["seq"],
        prev=value["prev"],
        ts=value["ts"],
        ref=value["ref"],
        kind=value["kind"],
        writer=value["writer"],
        fields=extra,
        line=body,
        hash=line_hash(body),
    )


def _check(value: Mapping[str, Any]) -> None:
    if value.get("v") != VERSION:
        raise LedgerFormatError("unknown version")
    kind = value.get("kind")
    if not isinstance(kind, str) or kind not in FIELDS:
        raise LedgerFormatError("unknown kind")
    if not _count(value.get("seq")) or not _count(value.get("ts")):
        raise LedgerFormatError("bad seq or ts")
    if not _pattern(_SHA256)(value.get("prev")):
        raise LedgerFormatError("bad prev")
    if value.get("writer") not in ("gateway", "vault"):
        raise LedgerFormatError("bad writer")
    ref = value.get("ref")
    if kind in _NO_REF:
        if ref is not None:
            raise LedgerFormatError(f"a {kind} record has no ref")
    elif not (isinstance(ref, str) and _REF.match(ref)):
        raise LedgerFormatError("bad ref")
    checks = FIELDS[kind]
    names = set(value) - set(_COMMON)
    if names != set(checks):
        raise LedgerFormatError(f"a {kind} record has the wrong fields")
    for name, check in checks.items():
        if not check(value[name]):
            raise LedgerFormatError(f"bad {name} in a {kind} record")


# --- the chain -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Verified:
    """The result of walking a chain: the last good record, and the first break, if any."""

    head_seq: int  # -1 when there are no records
    head_hash: str
    records: int
    broken_at: int | None  # the seq (or, for an unparsable line, the expected seq) that broke


def verify(lines: Iterable[bytes], *, prev: str = GENESIS, seq: int = 0) -> Verified:
    """Walk ``lines`` as a chain that starts after ``prev`` with ``seq``.

    Stops at the first line that doesn't parse, skips a seq, or doesn't chain from the one before.
    """
    head_seq, head_hash, count = seq - 1, prev, 0
    for line in lines:
        try:
            record = parse(line)
        except LedgerFormatError:
            return Verified(head_seq, head_hash, count, head_seq + 1)
        if record.seq != head_seq + 1 or record.prev != head_hash:
            return Verified(head_seq, head_hash, count, record.seq)
        head_seq, head_hash, count = record.seq, record.hash, count + 1
    return Verified(head_seq, head_hash, count, None)


def torn_tail(data: bytes) -> int:
    """How many bytes at the end of a file's ``data`` aren't a complete, valid record.

    A crash mid-write leaves a last line with no newline, or one that doesn't parse. Only that
    tail is torn: an earlier bad line is a broken chain, found by :func:`verify`.
    """
    if not data:
        return 0
    if not data.endswith(b"\n"):
        cut = data.rfind(b"\n") + 1
        return len(data) - cut
    start = data.rfind(b"\n", 0, len(data) - 1) + 1
    try:
        parse(data[start:])
    except LedgerFormatError:
        return len(data) - start
    return 0


# --- recovery ------------------------------------------------------------------------------------


def open_refs(records: Iterable[Record]) -> dict[str, list[Record]]:
    """The refs with an ``asked`` record and no ``outcome``, each with its records in order."""
    found: dict[str, list[Record]] = {}
    for record in records:
        if record.ref is None:
            continue
        if record.kind == "asked":
            found[record.ref] = [record]
        elif record.ref in found:
            if record.kind == "outcome":
                del found[record.ref]
            else:
                found[record.ref].append(record)
    return found


@dataclass(frozen=True)
class Step:
    """A record recovery writes: kind, ref and fields (seq, prev and ts come at write time)."""

    kind: Kind
    ref: str | None
    fields: Mapping[str, Any]


def recovery_plan(open_: Mapping[str, Sequence[Record]]) -> list[Step]:
    """Close every open ref with exactly one ``outcome``, then one ``recovered`` (F.5 step 4).

    - ``asked`` and nothing else: ``decided abandoned``, then ``outcome not_sent``;
    - a decision other than ``accept``: ``outcome not_sent``;
    - ``decided accept``: ``outcome unknown``, since the call may have run.

    The same open refs always give the same steps, in ref order.
    """
    steps: list[Step] = []
    counts = {"abandoned": 0, "not_sent": 0, "unknown": 0}
    for ref in sorted(open_):
        records = open_[ref]
        planned = next((r.fields["writes"] for r in records if r.kind == "asked"), 0)
        decisions = [r.fields["decision"] for r in records if r.kind == "decided"]
        if not decisions:
            steps.append(Step("decided", ref, {"decision": "abandoned", "waited_ms": 0}))
            counts["abandoned"] += 1
            outcome = "not_sent"
        elif decisions[-1] == "accept":
            outcome = "unknown"
        else:
            outcome = "not_sent"
        counts[outcome] += 1
        unknown = planned if outcome == "unknown" else 0  # any planned write may have gone out
        fields = {"outcome": outcome, "detail": "restart", "writes_sent": 0}
        steps.append(Step("outcome", ref, {**fields, "writes_unknown": unknown}))
    if steps:
        steps.append(Step("recovered", None, counts))
    return steps
