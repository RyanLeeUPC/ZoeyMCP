"""Example records toolkit: batch tools against an HTTP records API (M4 design K.2, S16).

A sandbox that can't loop over MCP calls makes one call per batch. Reads are routine. Adding and
archiving are consequential: each batch is one plan, shown in one prompt, and each added record is
read back. There is no delete tool, and the policy's route has no DELETE rule either: "archive,
never delete" is the vault's to enforce, not only this code's.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, TypedDict

from zoeymcp.common.canonical import JSONValue
from zoeymcp.toolkit import (
    Batch,
    BatchResult,
    ItemResult,
    Plan,
    PrepareContext,
    Range,
    Show,
    Text,
    ToolContext,
    Toolkit,
    ToolkitError,
    VaultError,
    VaultSlot,
    Write,
    batch,
)

toolkit = Toolkit("records", slots={"db": "http"}, description="Read, add and archive records.")


class NewRecord(TypedDict):
    title: Annotated[str, Text(min=1, max=120, single_line=True)]
    amount: Annotated[int, Range(ge=0, le=1_000_000_000)]
    day: Annotated[str, Text(min=10, max=10, ascii_only=True, pattern=r"\d{4}-\d{2}-\d{2}")]


# Inside the vault's segment characters and never "." or "..": an id stays one plain segment.
RecordId = Annotated[
    str, Text(min=1, max=64, single_line=True, ascii_only=True, pattern=r"[A-Za-z0-9_-]{1,64}")
]


def _path(record_id: str) -> str:
    return f"/v1/records/{record_id}"


@toolkit.tool(consequential=False)
async def get_records(
    ctx: ToolContext, ids: Annotated[list[RecordId], Batch(max=50)]
) -> BatchResult:
    """Fetch up to 50 records by id in one call."""
    db = ctx.vault("db")
    return await batch(ids, lambda i: _fetch(db, i))


async def _fetch(db: VaultSlot, record_id: str) -> JSONValue:
    found: JSONValue = await db.get_object(_path(record_id))
    return found


async def plan_add(ctx: PrepareContext, records: list[NewRecord]) -> Plan:
    body: dict[str, JSONValue] = {"records": [dict(r) for r in records]}
    layout = Show.items(
        "Records", "/records", fields=[("title", "/title"), ("amount", "/amount"), ("day", "/day")]
    )
    return Plan(
        f"Add {len(records)} records", [Write.post("/v1/records/batch", body, show=[layout])]
    )


@toolkit.tool(consequential=True, prepare=plan_add)
async def add_records(
    ctx: ToolContext, records: Annotated[list[NewRecord], Batch(max=25)]
) -> BatchResult:
    """Add up to 25 records in one approved call. Each one is read back."""
    if ctx.plan is None:
        raise ToolkitError("no approved plan")
    db = ctx.vault("db")
    created = await db.send(ctx.plan.writes[0])
    return await read_back(db, records, created)


async def read_back(
    db: VaultSlot, records: Sequence[NewRecord], created: dict[str, JSONValue]
) -> BatchResult:
    """Per record: its id if it was stored as sent, else why not. Never stops early."""
    answers: dict[int, Any] = {}
    listed = created.get("created")
    if isinstance(listed, list):
        for entry in listed:
            if isinstance(entry, dict) and isinstance(entry.get("index"), int):
                answers[entry["index"]] = entry

    async def one(index: int) -> ItemResult:
        entry = answers.get(index)
        if entry is None:
            return ItemResult(index, False, error="no answer for this record")
        record_id = entry.get("id")
        if not isinstance(record_id, str):
            return ItemResult(index, False, error="refused by the records API")
        try:
            stored = await db.get_object(_path(record_id))
        except VaultError as exc:
            return ItemResult(index, False, error=f"read-back failed ({exc.code or exc.status})")
        wanted = records[index]
        if any(stored.get(key) != wanted.get(key) for key in ("title", "amount", "day")):
            return ItemResult(index, False, value=record_id, error="read-back differs")
        return ItemResult(index, True, value=record_id)

    items = [await one(i) for i in range(len(records))]
    return BatchResult(tuple(items))


async def plan_archive(ctx: PrepareContext, ids: list[str]) -> Plan:
    return Plan(
        f"Archive {len(ids)} records",
        [Write.post("/v1/records/archive", {"ids": list(ids)}, show=[Show.line("Ids", "/ids")])],
    )


@toolkit.tool(consequential=True, prepare=plan_archive)
async def archive_records(ctx: ToolContext, ids: Annotated[list[RecordId], Batch(max=25)]) -> str:
    """Archive up to 25 records in one approved call. Nothing is ever deleted."""
    if ctx.plan is None:
        raise ToolkitError("no approved plan")
    answer = await ctx.vault("db").send(ctx.plan.writes[0])
    return f"archived {answer.get('archived', 0)} of {len(ids)}"
