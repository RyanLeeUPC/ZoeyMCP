"""The approval ledger's records joined by ref (M5 design J.5; M8 design J.2).

One entry per ref, in the order each was asked, holding that call's records by kind and writer,
and one per ledger-level record (``recovered``, ``repaired``). ``zoeymcp ledger`` renders these
entries, and the vault's ledger view joins its copy of the gateway's ledger with the same code,
then merges each call's records from its own chain by ref (each chain read alone, so neither
asking a ref again hides the other's call). Chains join by ref only, never by digest (each keys
its digests its own way).

This module is pure and standard library only: the CLI may run in the vault's environment, and the
vault never imports the CLI or the gateway.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Call:
    """One ref's records by ``(kind, writer)``: ``asked`` always, from at least one writer, and
    ``decided`` and ``outcome`` once written, each writer's its own (M8 design J.2).

    A later record of a kind from the same writer replaces the earlier one.
    """

    ref: str
    records: Mapping[tuple[str, str], Mapping[str, Any]]

    def get(self, kind: str, *writers: str) -> Mapping[str, Any] | None:
        """``kind``'s record from the first of ``writers`` that wrote one, None if none did.
        Naming no writer, the record of that kind written first, whoever wrote it."""
        if not writers:
            return next((r for (k, _), r in self.records.items() if k == kind), None)
        for writer in writers:
            found = self.records.get((kind, writer))
            if found is not None:
                return found
        return None


def join(
    records: Iterable[Mapping[str, Any]], *, since: int | None = None
) -> list[Call | Mapping[str, Any]]:
    """One :class:`Call` per ref, in the order each was asked, and each ledger-level record as is.

    With ``since`` (epoch milliseconds), only the refs asked at or after it and the ledger-level
    records written at or after it. A record whose ref has no ``asked`` record kept is dropped.
    An ``asked`` from a writer the ref's entry has none from joins that entry (the other chain's
    record of the same call); a second from the same writer starts a new entry, so a ref one
    writer asked twice is an entry at each, both holding its latest records.
    """
    calls: dict[str, dict[tuple[str, str], Mapping[str, Any]]] = {}
    order: list[str | Mapping[str, Any]] = []
    for record in records:
        ref, kind, writer = record.get("ref"), record.get("kind"), record.get("writer")
        if ref is None:
            if since is None or record["ts"] >= since:
                order.append(record)
            continue
        if not isinstance(kind, str) or not isinstance(writer, str):
            continue
        entry = calls.get(ref)
        if kind == "asked" and (entry is None or ("asked", writer) in entry):
            if since is not None and record["ts"] < since:
                continue
            calls[ref] = {("asked", writer): record}
            order.append(ref)
        elif entry is not None:
            entry[(kind, writer)] = record
    return [Call(item, calls[item]) if isinstance(item, str) else item for item in order]
