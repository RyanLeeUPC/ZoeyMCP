"""``zoeymcp ledger``: the approval ledger, read through the gateway's admin socket (M4 design F.4).

The default output renders each ref's records, joined by :mod:`zoeymcp.common.ledgerjoin`, as one
line: when it was asked, the ref, the client, ``server/tool``, the era, the decision and the
outcome. ``--format json`` prints the records themselves, keyed digests included. Nothing here
imports the gateway: the CLI may run in the vault's environment.

``zoeymcp ledger --vault`` reads the vault's reported copy instead (M5 design J.5): the rows the
vault's view makes, each with its sends, and the copy's state; :func:`vault_lines` renders them
and :func:`restart_lines` a chain restart's plan. Their strings are the gateway's: the CLI writes
them through ``review.write_lines``, which shows control characters as text.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, TextIO

from ..common import ledgerjoin

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
    out = []
    for entry in ledgerjoin.join(records, since=since):
        if not isinstance(entry, ledgerjoin.Call):
            fields = {k: v for k, v in entry.items() if k not in _COMMON}
            detail = " ".join(f"{k}={v}" for k, v in sorted(fields.items()))
            out.append(f"{_when(entry['ts'])} ledger {entry['kind']} {detail}".rstrip())
            continue
        call = entry.records
        asked = call["asked"]
        decided = call.get("decided", {}).get("decision", "-")
        outcome = call.get("outcome")
        result = "-" if outcome is None else outcome["outcome"]
        if outcome is not None and outcome.get("detail"):
            result += f" ({outcome['detail']})"
        out.append(
            f"{_when(asked['ts'])} {entry.ref} {asked['client']} {asked['server']}/{asked['tool']} "
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


# --- the vault's reported copy (M5 design J.4, J.5) ----------------------------------------------

RESTART_HINT = "after deciding why, run: zoeymcp ledger --vault --restart-chain"


def vault_lines(page: dict[str, Any]) -> list[str]:
    """The copy's state, then a page of rows oldest first, its orphan sends and archives."""
    state = page["state"]
    if state["head_seq"] is None:
        out = [f"copy: {state['state']}, nothing reported yet"]
    else:
        moved = state["reported_ago"]
        out = [
            f"copy: {state['state']}, head seq {state['head_seq']} ({state['head_hash']}), "
            f"chain from seq {state['start_seq']}"
            + ("" if moved is None else f", head moved {moved} s ago")
        ]
    if state.get("broken_at") is not None:
        out.append(f"broken: the copy's files stop chaining at seq {state['broken_at']}")
    refused = page.get("refused")
    if refused:
        out.append(f"refused: {_refusal(refused)}; {RESTART_HINT}")
    for row in reversed(page["rows"]):
        out.extend(_row_lines(row))
    for orphan in page["orphans"]:
        out.append(
            f"orphan send {orphan['key']} on {orphan['connector']}: {orphan['state']} at "
            f"{orphan['at']} ({orphan['flag']})"
        )
    for epoch in page.get("archives", []):
        line = f"archived {epoch['name']}: {_epoch(epoch)}"
        out.append(line + (", files dropped" if epoch["dropped"] else ""))
    if page["next"] is not None:
        out.append(f"older rows: zoeymcp ledger --vault --before {page['next']}")
    if page["rows"]:
        out.append("each row is as reported by the gateway")
    return out


def _refusal(refused: dict[str, Any]) -> str:
    return (
        f"{refused['reason']} at seq {refused['offered_seq']} (held seq {refused['held_seq']}, "
        f"{_when(refused['at'])})"
    )


def _row_lines(row: dict[str, Any]) -> list[str]:
    if row["kind"] != "call":
        detail = " ".join(f"{k}={v}" for k, v in sorted(row["fields"].items()))
        return [f"{row['at']} ledger {row['kind']} {detail}".rstrip()]
    result = row["outcome"] or "-"
    if row["detail"]:
        result += f" ({row['detail']})"
    out = [
        f"{row['at']} {row['ref']} {row['client']} {row['server']}/{row['tool']} {row['era']} "
        f"{row['decision'] or '-'} {result}"
    ]
    if row["not_in_policy"]:
        out.append(f"  not in the current policy: {', '.join(row['not_in_policy'])}")
    for send in row["journal"]:
        code = "-" if send["smtp_code"] is None else send["smtp_code"]
        out.append(f"  send {send['key']} {send['state']} {code} {send['at']}")
    return out


def _epoch(epoch: dict[str, Any]) -> str:
    return (
        f"seq {epoch['first_seq']}-{epoch['head_seq']} (head {epoch['head_hash']}), last "
        f"received {_when(epoch['received_ms'])}, {epoch['size']} bytes"
    )


def restart_lines(plan: dict[str, Any]) -> list[str]:
    """What a restart of the chain does, for the operator to decide on."""
    out = [f"the copy is {plan['state']}"]
    if plan["refused"]:
        out[0] += f": {_refusal(plan['refused'])}"
    archive = plan["archive"]
    out.append("archive: " + ("nothing (no live chain)" if archive is None else _epoch(archive)))
    for epoch in plan["drop"]:
        name = epoch["name"] or "the live chain"
        out.append(f"delete {name}: {_epoch(epoch)}; its head stays as an anchor")
    out.append("the next report from the gateway then starts a new chain, on trust")
    return out
