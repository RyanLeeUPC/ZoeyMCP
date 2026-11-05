"""``zoeymcp ledger``: the approval ledger, read through the gateway's admin socket (M4 design F.4).

The default output renders each ref's records, joined by :mod:`zoeymcp.common.ledgerjoin`, as one
line: when it was asked, the ref, the client, ``server/tool``, the era, the decision and the
outcome. ``--format json`` prints the records themselves, keyed digests included. Nothing here
imports the gateway: the CLI may run in the vault's environment.

``zoeymcp ledger --vault`` reads the vault's reported copy instead (M5 design J.5): the rows the
vault's view makes, each with its sends, and the copy's state; :func:`vault_lines` renders them
(from M8, a row's records the vault's own chain wrote, the other chain's records, where the
two chains disagree and the calls only the vault's chain holds, M8 design J.2) and
:func:`restart_lines` a chain restart's plan. Their strings are the gateway's: the CLI writes
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
from .review import counted

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
        asked = next(iter(entry.records.values()))  # an entry starts with its asked record
        decided = (entry.get("decided") or {}).get("decision", "-")
        outcome = entry.get("outcome")
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
# An orphan send's flag (J.5), in words; one this CLI doesn't know is printed as it is.
ORPHAN_WORDS = {
    "no_ledger_record": "no ledger record holds its call, and the vault's own chain holds no "
    "accept of it",
    "not_yet_reported": "not reported yet",
    "older_than_copy": "older than the ledger copy: can't be checked",
}
# A call only the vault's own chain holds (M8 design J.2, J.3), by the same flags.
VAULT_ONLY_WORDS = {
    "no_ledger_record": "the copy has had reports since and holds no record of it",
    "not_yet_reported": "not reported yet",
    "older_than_copy": "older than the ledger copy: can't be checked",
}


def vault_lines(page: dict[str, Any]) -> list[str]:
    """The copy's state, then a page of rows oldest first, its orphan sends, the calls only the
    vault's own chain holds, oldest first, and archives."""
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
    if page.get("chain_readable") is False:
        out.append("vault chain: can't be read, so each row is the copy's alone")
    for row in reversed(page["rows"]):
        out.extend(_row_lines(row))
    for orphan in page["orphans"]:
        flag = orphan["flag"]
        words = f"{flag}: {ORPHAN_WORDS[flag]}" if flag in ORPHAN_WORDS else flag
        out.append(
            f"orphan send {orphan['key']} on {orphan['connector']}: {orphan['state']} at "
            f"{orphan['at']} ({words})"
        )
    alone = page.get("vault_only", [])
    for row in reversed(alone):
        flag = row["flag"]
        words = f"{flag}: {VAULT_ONLY_WORDS[flag]}" if flag in VAULT_ONLY_WORDS else flag
        first, *rest = _row_lines(row)
        out.extend([first, f"  only the vault's own chain holds this call ({words})", *rest])
    if page.get("vault_only_more"):
        older = counted(page["vault_only_more"], "older call")
        out.append(f"{older} only the vault's own chain holds")
    for epoch in page.get("archives", []):
        line = f"archived {epoch['name']}: {_epoch(epoch)}"
        out.append(line + (", files dropped" if epoch["dropped"] else ""))
    if page["next"] is not None:
        out.append(f"older rows: zoeymcp ledger --vault --before {page['next']}")
    if any(_vault_wrote(row) for row in [*page["rows"], *alone]):
        out.append("each row is as reported by the gateway, but for what it says the vault wrote")
    elif page["rows"]:
        out.append("each row is as reported by the gateway")
    return out


def _vault_wrote(row: dict[str, Any]) -> bool:
    if row["kind"] != "call":
        return bool(row["writer"] != "gateway")
    others = row.get("others", [])
    return any(w != "gateway" for w in row["writers"].values()) or any(
        other["writer"] != "gateway" for other in others
    )


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
    decision = row["decision"] or "-"
    if row.get("via") not in (None, "none"):
        decision += f" via {row['via']}"
    out = [
        f"{row['at']} {row['ref']} {row['client']} {row['server']}/{row['tool']} {row['era']} "
        f"{decision} {result}"
    ]
    # M8 (J.2): where the vault held it, who wrote what, the other chain's records, a dispute.
    vault = sorted(kind for kind, writer in row["writers"].items() if writer != "gateway")
    if row.get("where") == "vault":
        out.append("  held by the vault")
    if vault:
        out.append(f"  written by the vault: {', '.join(vault)}")
    if row.get("disagree"):
        out.append("  the chains disagree: the vault's decision and the gateway's differ")
    for other in row.get("others", []):
        value = other.get("decision") or other.get("outcome")
        if other.get("detail"):
            value += f" ({other['detail']})"
        by = "reported by the gateway" if other["writer"] == "gateway" else "written by the vault"
        out.append(f"  also {other['kind']} {value}, {by}")
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
