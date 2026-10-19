"""Batch results, and what the agent reads for a result or an error (M4 design G.5, G.7).

A batch never stops early and never rolls back: each item gets its own outcome. The texts an
agent reads for an error never carry an exception's message, which can hold argument values;
only a :class:`ToolkitError` that passes the text rules is shown.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ..common import canonical
from ..common.approvaltext import LayoutError
from ..common.canonical import JSONValue
from .context import ToolkitError, VaultError

MAX_CONCURRENCY = 4


@dataclass(frozen=True)
class ItemResult:
    index: int
    ok: bool
    value: JSONValue = None
    error: str | None = None

    def data(self) -> dict[str, JSONValue]:
        if self.ok:
            return {"index": self.index, "ok": True, "value": self.value}
        found: dict[str, JSONValue] = {"index": self.index, "ok": False, "error": self.error}
        if self.value is not None:  # a failure may still name what it concerns, like an id
            found["value"] = self.value
        return found


@dataclass(frozen=True)
class BatchResult:
    """Per-item outcomes, in the items' order."""

    items: tuple[ItemResult, ...] = field(default=())

    @property
    def ok(self) -> int:
        return sum(1 for item in self.items if item.ok)

    def data(self) -> dict[str, JSONValue]:
        return {
            "ok": self.ok,
            "failed": len(self.items) - self.ok,
            "items": [item.data() for item in self.items],
        }


def item_error(exc: BaseException) -> str:
    """The text a failed item carries."""
    if isinstance(exc, ToolkitError):
        return exc.shown
    if isinstance(exc, VaultError):
        return f"vault answered {exc.status} {exc.code or ''}".rstrip()
    return "error"


async def batch[T](
    items: Iterable[T],
    fn: Callable[[T], Awaitable[JSONValue]],
    *,
    concurrency: int = MAX_CONCURRENCY,
) -> BatchResult:
    """``fn`` over every item, at most ``concurrency`` at a time (the gateway allows 4 vault
    requests in flight per call). A failure is that item's outcome; the rest still run."""
    listed = list(items)
    gate = asyncio.Semaphore(max(1, min(concurrency, MAX_CONCURRENCY)))

    async def one(index: int, item: T) -> ItemResult:
        async with gate:
            try:
                return ItemResult(index, True, value=await fn(item))
            except Exception as exc:  # every item gets an outcome
                return ItemResult(index, False, error=item_error(exc))

    found = await asyncio.gather(*(one(i, item) for i, item in enumerate(listed)))
    return BatchResult(tuple(found))


def render(value: Any) -> str:
    """A tool's return value as the one text block the agent gets: a ``str`` as it is, a
    :class:`BatchResult` as canonical JSON. Anything else is a toolkit bug."""
    if isinstance(value, str):
        return value
    if isinstance(value, BatchResult):
        return canonical.dumps_canonical(value.data()).decode()
    raise TypeError("a tool returns a str or a BatchResult")


@dataclass(frozen=True)
class Failure:
    """What the agent reads, and the log line's fields (never a message or a value)."""

    text: str
    event: str
    fields: dict[str, Any]


def failure(exc: BaseException, ref: str) -> Failure:
    """G.7's table, for anything raised in a body or a ``prepare`` step."""
    if isinstance(exc, ToolkitError):
        return Failure(f"{exc.shown} (ref {ref})", "toolkit_tool_error", {})
    if isinstance(exc, VaultError):
        code = f" {exc.code}" if exc.code else ""
        return Failure(
            f"toolkit error: vault answered {exc.status}{code} (ref {ref})",
            "toolkit_error",
            {"status": exc.status, "code": exc.code},
        )
    if isinstance(exc, TimeoutError):
        return Failure(f"toolkit timed out (ref {ref})", "toolkit_error", {"error_type": "timeout"})
    kind = "LayoutError" if isinstance(exc, LayoutError) else type(exc).__name__
    return Failure(f"toolkit error (ref {ref})", "toolkit_error", {"error_type": kind})
