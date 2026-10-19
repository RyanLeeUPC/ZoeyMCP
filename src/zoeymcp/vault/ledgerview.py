"""The ledger view: the vault's copy, one row per call, with the send journal (M5 design J.5, J.6).

Pure, so each flag can be tested. The records are joined by :mod:`zoeymcp.common.ledgerjoin`, the
code ``zoeymcp ledger`` prints with, and flattened into rows, newest first, a page at a time:

- **No keyed digests and no pin.** An ``asked`` record's ``args``, ``text`` and ``pin`` never
  reach a row; ``zoeymcp ledger check`` in the gateway's container checks arguments (Q12).
- **Who wrote each record.** Every row carries each record's ``writer``: the gateway's, as
  reported, and from M8 the vault's own chain joined in by ref (``approved_elsewhere``,
  ``pending``). A row is a claim the gateway made, and the page says so.
- **The journal join (D-25).** A send's ``Idempotency-Key`` up to its last dot is the call's ref.
  A row shows its sends' state, SMTP code and time, never the Message-ID or ``req_hmac``. A send
  whose ref the copy doesn't hold is an orphan: ``no_ledger_record`` once the copy has received a
  report since that send began, else ``not_yet_reported``. It shows a send by a caller that can't
  write the gateway's ledger; a compromised gateway can cover its own sends with records it makes
  up (threat T4).
- **Names the current policy lacks** are listed in a row's ``not_in_policy``.

Every string here is the gateway's or the journal's: the portal shows each through
``display.shown``.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

from ..common import ledgerjoin
from .reports import Held

MAX_LIMIT: Final = 200
NAMED: Final = ("client", "server", "tool")  # the asked record's names a policy can lack
_COMMON: Final = frozenset({"v", "seq", "prev", "ts", "ref", "kind", "writer"})

Flag = Literal["no_ledger_record", "not_yet_reported"]


def when(ts: int) -> str:
    """Epoch milliseconds as ``2026-10-19T09:12:03Z``."""
    return datetime.fromtimestamp(ts // 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Send:
    """One ``Idempotency-Key``'s journal records: its latest state, and when it began and ended."""

    connector: str
    key: str
    state: str
    smtp_code: int | None
    started_ms: int
    at_ms: int

    @property
    def ref(self) -> str:
        return self.key.rpartition(".")[0]


def sends(journals: Mapping[str, Iterable[Mapping[str, Any]]]) -> list[Send]:
    """Each connector's journal records (as parsed, in order) by key, in the order each began.

    A ``sending`` record starts a send; the first ``sent``, ``failed`` or ``unknown`` after it
    ends it, as the connector's own journal reads them. An ending whose ``sending`` is gone is
    shown as it is.
    """
    found: dict[tuple[str, str], Send] = {}
    for connector, records in journals.items():
        for record in records:
            kind, key, ts = record["kind"], record["key"], record["ts"]
            send = found.get((connector, key))
            if kind == "sending":
                found[(connector, key)] = Send(connector, key, kind, None, ts, ts)
            elif send is None:
                found[(connector, key)] = Send(
                    connector, key, kind, record.get("smtp_code"), ts, ts
                )
            elif send.state == "sending":
                send.state, send.smtp_code, send.at_ms = kind, record.get("smtp_code"), ts
    return list(found.values())


def state(held: Held, *, now: int, broken_at: int | None = None) -> dict[str, Any]:
    """The copy's state line: ``reported_ago`` is how many seconds since the head last moved.
    ``broken_at``: the seq where the copy's files stop chaining, if recovery found one (J.4)."""
    received = held.received_ms
    return {
        "state": held.state,
        "head_seq": held.head_seq,
        "head_hash": held.head_hash,
        "start_seq": held.start_seq,
        "reported_ago": None if received is None else max(0, now - received) // 1000,
        "broken_at": broken_at,
    }


def page(
    records: Iterable[Mapping[str, Any]],
    *,
    held: Held,
    journals: Mapping[str, Iterable[Mapping[str, Any]]],
    now: int,
    before: int | None = None,
    limit: int = MAX_LIMIT,
    known: Mapping[str, Collection[str]] | None = None,
    broken_at: int | None = None,
) -> dict[str, Any]:
    """One page of the view: the rows whose seq is below ``before``, newest first, at most
    ``limit`` (1 to :data:`MAX_LIMIT`), and ``next``, the ``before`` of the page after it (None at
    the end). Orphans are on the first page. ``known``: the current policy's names by field
    (``client``, ``server``, ``tool``); a field it doesn't list isn't checked.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    records = list(records)
    by_ref: dict[str, list[Send]] = {}
    found = sends(journals)
    for send in found:
        by_ref.setdefault(send.ref, []).append(send)
    rows: list[dict[str, Any]] = []
    calls: set[int] = set()
    for entry in ledgerjoin.join(records):
        row = _row(entry, by_ref, known or {})
        if row["kind"] == "call":
            # A ref asked twice is two entries holding the same, latest, records: one row.
            if row["seq"] in calls:
                continue
            calls.add(row["seq"])
        rows.append(row)
    rows.sort(key=lambda row: row["seq"], reverse=True)
    if before is not None:
        rows = [row for row in rows if row["seq"] < before]
    shown = rows[:limit]
    refs = {record["ref"] for record in records if record.get("ref") is not None}
    return {
        "state": state(held, now=now, broken_at=broken_at),
        "rows": shown,
        "orphans": [] if before is not None else orphans(found, refs, held.received_ms),
        "next": shown[-1]["seq"] if len(rows) > limit else None,
    }


def orphans(
    found: Iterable[Send], refs: Collection[str], received_ms: int | None
) -> list[dict[str, Any]]:
    """The sends whose ref the copy doesn't hold, newest first, each flagged."""
    out = []
    for send in sorted(found, key=lambda s: s.started_ms, reverse=True):
        if send.ref in refs:
            continue
        reported = received_ms is not None and received_ms > send.started_ms
        flag: Flag = "no_ledger_record" if reported else "not_yet_reported"
        out.append(
            {
                "connector": send.connector,
                "key": send.key,
                "state": send.state,
                "at": when(send.at_ms),
                "flag": flag,
            }
        )
    return out


def _row(
    entry: ledgerjoin.Call | Mapping[str, Any],
    by_ref: Mapping[str, list[Send]],
    known: Mapping[str, Collection[str]],
) -> dict[str, Any]:
    if not isinstance(entry, ledgerjoin.Call):
        return {
            "kind": entry["kind"],
            "seq": entry["seq"],
            "at": when(entry["ts"]),
            "writer": entry["writer"],
            "fields": {k: v for k, v in entry.items() if k not in _COMMON},
        }
    asked = entry.records["asked"]
    decided = entry.records.get("decided", {})
    outcome = entry.records.get("outcome", {})
    return {
        "kind": "call",
        "seq": asked["seq"],
        "ref": entry.ref,
        "at": when(asked["ts"]),
        "client": asked["client"],
        "server": asked["server"],
        "tool": asked["tool"],
        "era": asked["era"],
        "decision": decided.get("decision"),
        "waited_ms": decided.get("waited_ms"),
        "outcome": outcome.get("outcome"),
        "detail": outcome.get("detail"),
        "writes": asked["writes"],
        "writes_sent": outcome.get("writes_sent"),
        "writes_unknown": outcome.get("writes_unknown"),
        "writers": {kind: record["writer"] for kind, record in entry.records.items()},
        "not_in_policy": [
            name for name in NAMED if name in known and asked[name] not in known[name]
        ],
        "journal": [
            {
                "key": send.key,
                "state": send.state,
                "smtp_code": send.smtp_code,
                "at": when(send.at_ms),
            }
            for send in by_ref.get(entry.ref, [])
        ],
    }
