"""The approval ledger's records joined by ref (M5 design J.5).

One entry per ref, in the order each was asked, holding that call's records by kind, and one per
ledger-level record (``recovered``, ``repaired``). ``zoeymcp ledger`` renders these entries, and
the vault's ledger view joins its copy of the ledger with the same code.

This module is pure and standard library only: the CLI may run in the vault's environment, and the
vault never imports the CLI or the gateway.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Call:
    """One ref's records by kind: ``asked`` always, ``decided`` and ``outcome`` once written.

    A later record of a kind replaces an earlier one. Each record keeps its own ``writer``.
    """

    ref: str
    records: Mapping[str, Mapping[str, Any]]


def join(
    records: Iterable[Mapping[str, Any]], *, since: int | None = None
) -> list[Call | Mapping[str, Any]]:
    """One :class:`Call` per ref, in the order each was asked, and each ledger-level record as is.

    With ``since`` (epoch milliseconds), only the refs asked at or after it and the ledger-level
    records written at or after it. A record whose ref has no ``asked`` record kept is dropped, and
    a ref asked twice is an entry at each, both holding its latest records.
    """
    calls: dict[str, dict[str, Mapping[str, Any]]] = {}
    order: list[str | Mapping[str, Any]] = []
    for record in records:
        ref, kind = record.get("ref"), record.get("kind")
        if ref is None:
            if since is None or record["ts"] >= since:
                order.append(record)
            continue
        if kind == "asked":
            if since is not None and record["ts"] < since:
                continue
            calls[ref] = {"asked": record}
            order.append(ref)
        elif ref in calls and isinstance(kind, str):
            calls[ref][kind] = record
    return [Call(item, calls[item]) if isinstance(item, str) else item for item in order]
