"""``zoeymcp ledger``: the approval ledger, read through the gateway's admin socket (M4 design F.4).

The default output joins each ref's records into one line: when it was asked, the ref, the client,
``server/tool``, the era, the decision and the outcome. ``--format json`` prints the records
themselves, keyed digests included. Nothing here imports the gateway: the CLI may run in the
vault's environment.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, TextIO

_SINCE = re.compile(r"^([0-9]{1,6})([mhd])$")
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}
_COMMON = frozenset({"v", "seq", "prev", "ts", "ref", "kind", "writer"})


class UsageError(ValueError):
    pass


def since_ms(value: str | None, now: float | None = None) -> int | None:
    """``7d``, ``12h`` or ``30m`` before now, in epoch milliseconds."""
    if value is None:
        return None
    match = _SINCE.fullmatch(value)
    if match is None:
        raise UsageError("--since takes a number and m, h or d, like 7d")
    seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2)]
    current = time.time() if now is None else now
    return int((current - seconds) * 1000)


def _when(ts: int) -> str:
    return datetime.fromtimestamp(ts / 1000, UTC).strftime("%Y-%m-%d %H:%M:%SZ")


def lines(records: Iterable[dict[str, Any]], *, since: int | None = None) -> list[str]:
    """One line per ref, in the order each was asked, and one per ledger-level record."""
    calls: dict[str, dict[str, Any]] = {}
    order: list[tuple[str, Any]] = []
    for record in records:
        ref, kind = record.get("ref"), record.get("kind")
        if ref is None:
            if since is None or record["ts"] >= since:
                order.append(("ledger", record))
            continue
        if kind == "asked":
            if since is not None and record["ts"] < since:
                continue
            calls[ref] = {"asked": record}
            order.append(("call", ref))
        elif ref in calls and isinstance(kind, str):
            calls[ref][kind] = record
    out = []
    for what, item in order:
        if what == "ledger":
            fields = {k: v for k, v in item.items() if k not in _COMMON}
            detail = " ".join(f"{k}={v}" for k, v in sorted(fields.items()))
            out.append(f"{_when(item['ts'])} ledger {item['kind']} {detail}".rstrip())
            continue
        call = calls[item]
        asked = call["asked"]
        decided = call.get("decided", {}).get("decision", "-")
        outcome = call.get("outcome")
        result = "-" if outcome is None else outcome["outcome"]
        if outcome is not None and outcome.get("detail"):
            result += f" ({outcome['detail']})"
        out.append(
            f"{_when(asked['ts'])} {item} {asked['client']} {asked['server']}/{asked['tool']} "
            f"{asked['era']} {decided} {result}"
        )
    return out


def verify_lines(result: dict[str, Any]) -> list[str]:
    head = f"head seq {result['head_seq']}, hash {result['head_hash']}"
    if result["ok"]:
        return [f"ok: {result['records']} records chain; {head}"]
    good = f"{result['records']} records chain before it"
    return [f"broken at seq {result['broken_at']}: {good}; {head}"]


def check_lines(result: dict[str, Any]) -> list[str]:
    if not result["found"]:
        return [f"{result['ref']}: no asked record (pruned, or never asked)"]
    if result["matches"]:
        return [f"{result['ref']}: the call had exactly these arguments"]
    return [f"{result['ref']}: these are not the call's arguments"]


def write(out: TextIO, rows: Iterable[str]) -> None:
    for row in rows:
        out.write(row + "\n")


def write_json(out: TextIO, records: Iterable[dict[str, Any]]) -> None:
    for record in records:
        out.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
