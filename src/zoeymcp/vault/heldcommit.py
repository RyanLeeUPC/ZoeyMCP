"""The vault's committed registry: an approved held call's forward (M8 design B.6, B.8; Z9).

A forward approved by a decision runs on :mod:`zoeymcp.common.committed` (the gateway's registry,
moved unchanged in step 2), never in the request's task: uvicorn's graceful cancel is
``task.cancel()``, which an anyio shield doesn't stop (M4 build note 6b). The vault starts each
decision's task itself (``VaultApp.decide``), so the registry runs the forward there, shielded,
and keeps its deadline for the stop. A caller that leaves stops receiving; the forward runs to
its end and its outcome reaches the chain. The vault's stop drains the registry up to each
forward's deadline, the held server's (or, for a connector, the writer tool's) effective
``call_timeout`` plus :data:`OUTCOME_MARGIN`, from the vault's own policy (I.1).

An answer is read to its end here, at most :data:`~zoeymcp.common.resultstore.MAX_RESULT_BYTES`,
so a held answer is buffered, never streamed: a relay reads on the request's task and closes the
upstream when the caller leaves, which would cut the forward and lose its outcome (F-51). Its
headers are filtered for the gateway and scrubbed, and its bytes scrubbed with the route's secret
variants (an event stream one event at a time), before the answer leaves by any way: to the
waiting request, or to the result store (:func:`read_answer`). The stored answer's reader
(:func:`~zoeymcp.common.heldresult.outcome_of`, the one ``check_approval`` reads it with)
classifies the full answer: ``ok``, ``tool_error`` from a result's ``isError``, else
``upstream_error``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, TypeVar

import httpx

from ..common.committed import Committed
from ..common.heldresult import media_type, outcome_of
from ..common.resultstore import MAX_RESULT_BYTES
from .request import (
    NDJSONScrubber,
    SSEScrubber,
    StreamEventTooLarge,
    filter_response_headers,
    scrub,
    scrub_headers,
)

T = TypeVar("T")

# Seconds past a forward's call_timeout for writing its outcome (the gateway's margin, I.2).
OUTCOME_MARGIN: Final = 10.0
SSE_TYPE: Final = "text/event-stream"
NDJSON_TYPE: Final = "application/x-ndjson"


@dataclass(frozen=True, repr=False)
class HeldAnswer:
    """An upstream's answer to an approved held call, read in full and scrubbed. ``too_large``:
    it was over :data:`~zoeymcp.common.resultstore.MAX_RESULT_BYTES`, or one of its events over
    the scrubber's limit, and its bytes were dropped. No ``repr``: it may hold what the tool
    returned."""

    status: int
    headers: tuple[tuple[str, str], ...]
    content_type: str
    body: bytes
    too_large: bool
    outcome: str
    scrubbed: int

    def __repr__(self) -> str:
        return f"HeldAnswer(status={self.status}, outcome={self.outcome})"


class HeldCommits:
    """The registry the vault's approved forwards run in."""

    def __init__(self) -> None:
        self.registry = Committed()

    def __len__(self) -> int:
        return len(self.registry)

    async def run(self, ref: str, seconds: float, work: Callable[[], Awaitable[T]]) -> T:
        """Run ``work``, the forward of ``ref``, which must end within ``seconds``, shielded in
        the decision's own task."""
        return await self.registry.run(ref, seconds, work)

    async def drain(self) -> list[str]:
        """At the vault's stop: wait for every forward up to its deadline, then cancel the rest
        (their outcome is then unknown). Returns the refs cancelled."""
        return await self.registry.drain()


async def read_answer(
    upstream: httpx.Response, variants: list[bytes], request_id: str | int
) -> HeldAnswer:
    """Read ``upstream`` to its end (bounded), then filter and scrub it for the gateway, and
    classify its outcome for the JSON-RPC request ``request_id``. The upstream is closed."""
    chunks: list[bytes] = []
    size = 0
    too_large = False
    try:
        async for chunk in upstream.aiter_bytes():
            size += len(chunk)
            if size > MAX_RESULT_BYTES:
                too_large = True
                break
            chunks.append(chunk)
    finally:
        await upstream.aclose()
    headers, hits = scrub_headers(
        filter_response_headers(upstream.headers.multi_items(), gateway=True), variants
    )
    content_type = upstream.headers.get("content-type", "")
    status = upstream.status_code
    # Too large to keep, or to scrub: its bytes are dropped (fail closed, as a relayed stream
    # does), and the call may well have run.
    lost = HeldAnswer(status, tuple(headers), content_type, b"", True, _lost(status), hits)
    if too_large:
        return lost
    body = b"".join(chunks)
    try:
        body, found = _scrubbed(body, content_type, variants)
    except StreamEventTooLarge:
        return lost
    outcome = outcome_of(status, content_type, body, request_id)
    return HeldAnswer(status, tuple(headers), content_type, body, False, outcome, hits + found)


def _lost(status: int) -> str:
    """The outcome of an answer whose bytes were dropped: ``unknown`` for a 2xx (the tool may
    have succeeded), else ``upstream_error``."""
    return "unknown" if 200 <= status <= 299 else "upstream_error"


def _scrubbed(body: bytes, content_type: str, variants: list[bytes]) -> tuple[bytes, int]:
    """``body`` with every secret variant redacted: an event stream one event (or line) at a
    time, as the request path relays it, anything else whole (B.8, F-51)."""
    if not variants:
        return body, 0
    kind = media_type(content_type)
    if kind in (SSE_TYPE, NDJSON_TYPE):
        scrubber = SSEScrubber(variants) if kind == SSE_TYPE else NDJSONScrubber(variants)
        out = scrubber.feed(body) + scrubber.finish()
        return out, scrubber.scrubbed
    return scrub(body, variants)
